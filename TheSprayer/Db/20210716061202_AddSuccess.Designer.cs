﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using TheSprayer.Db;

namespace TheSprayer.Db
{
    [DbContext(typeof(SprayDbContext))]
    [Migration("20210716061202_AddSuccess")]
    partial class AddSuccess
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "5.0.8");

            modelBuilder.Entity("TheSprayer.Models.CredentialAttempt", b =>
                {
                    b.Property<string>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("LastSprayTime")
                        .HasColumnType("TEXT");

                    b.Property<string>("Password")
                        .HasColumnType("TEXT");

                    b.Property<bool>("Success")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Username")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("Attempts");
                });
#pragma warning restore 612, 618
        }
    }
}
